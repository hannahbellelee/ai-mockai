/*
 * OpenAI API
 *
 * The OpenAI REST API. Please see https://platform.openai.com/docs/api-reference for more details.
 *
 * OpenAPI spec version: 2.1.0
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */
using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace IO.Swagger.Models
{
    /// <summary>
    /// The &#x60;File&#x60; object represents a document that has been uploaded to OpenAI.
    /// </summary>
    [DataContract]
    public partial class OpenAIFile : IEquatable<OpenAIFile>
    { 
        /// <summary>
        /// The file identifier, which can be referenced in the API endpoints.
        /// </summary>
        /// <value>The file identifier, which can be referenced in the API endpoints.</value>
        [Required]

        [DataMember(Name="id")]
        public string Id { get; set; }

        /// <summary>
        /// The size of the file, in bytes.
        /// </summary>
        /// <value>The size of the file, in bytes.</value>
        [Required]

        [DataMember(Name="bytes")]
        public int? Bytes { get; set; }

        /// <summary>
        /// The Unix timestamp (in seconds) for when the file was created.
        /// </summary>
        /// <value>The Unix timestamp (in seconds) for when the file was created.</value>
        [Required]

        [DataMember(Name="created_at")]
        public int? CreatedAt { get; set; }

        /// <summary>
        /// The name of the file.
        /// </summary>
        /// <value>The name of the file.</value>
        [Required]

        [DataMember(Name="filename")]
        public string Filename { get; set; }

        /// <summary>
        /// The object type, which is always `file`.
        /// </summary>
        /// <value>The object type, which is always `file`.</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum ObjectEnum
        {
            /// <summary>
            /// Enum FileEnum for file
            /// </summary>
            [EnumMember(Value = "file")]
            FileEnum = 0        }

        /// <summary>
        /// The object type, which is always &#x60;file&#x60;.
        /// </summary>
        /// <value>The object type, which is always &#x60;file&#x60;.</value>
        [Required]

        [DataMember(Name="object")]
        public ObjectEnum? _Object { get; set; }

        /// <summary>
        /// The intended purpose of the file. Supported values are `assistants`, `assistants_output`, `batch`, `batch_output`, `fine-tune`, `fine-tune-results` and `vision`.
        /// </summary>
        /// <value>The intended purpose of the file. Supported values are `assistants`, `assistants_output`, `batch`, `batch_output`, `fine-tune`, `fine-tune-results` and `vision`.</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum PurposeEnum
        {
            /// <summary>
            /// Enum AssistantsEnum for assistants
            /// </summary>
            [EnumMember(Value = "assistants")]
            AssistantsEnum = 0,
            /// <summary>
            /// Enum AssistantsOutputEnum for assistants_output
            /// </summary>
            [EnumMember(Value = "assistants_output")]
            AssistantsOutputEnum = 1,
            /// <summary>
            /// Enum BatchEnum for batch
            /// </summary>
            [EnumMember(Value = "batch")]
            BatchEnum = 2,
            /// <summary>
            /// Enum BatchOutputEnum for batch_output
            /// </summary>
            [EnumMember(Value = "batch_output")]
            BatchOutputEnum = 3,
            /// <summary>
            /// Enum FineTuneEnum for fine-tune
            /// </summary>
            [EnumMember(Value = "fine-tune")]
            FineTuneEnum = 4,
            /// <summary>
            /// Enum FineTuneResultsEnum for fine-tune-results
            /// </summary>
            [EnumMember(Value = "fine-tune-results")]
            FineTuneResultsEnum = 5,
            /// <summary>
            /// Enum VisionEnum for vision
            /// </summary>
            [EnumMember(Value = "vision")]
            VisionEnum = 6        }

        /// <summary>
        /// The intended purpose of the file. Supported values are &#x60;assistants&#x60;, &#x60;assistants_output&#x60;, &#x60;batch&#x60;, &#x60;batch_output&#x60;, &#x60;fine-tune&#x60;, &#x60;fine-tune-results&#x60; and &#x60;vision&#x60;.
        /// </summary>
        /// <value>The intended purpose of the file. Supported values are &#x60;assistants&#x60;, &#x60;assistants_output&#x60;, &#x60;batch&#x60;, &#x60;batch_output&#x60;, &#x60;fine-tune&#x60;, &#x60;fine-tune-results&#x60; and &#x60;vision&#x60;.</value>
        [Required]

        [DataMember(Name="purpose")]
        public PurposeEnum? Purpose { get; set; }

        /// <summary>
        /// Deprecated. The current status of the file, which can be either `uploaded`, `processed`, or `error`.
        /// </summary>
        /// <value>Deprecated. The current status of the file, which can be either `uploaded`, `processed`, or `error`.</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum StatusEnum
        {
            /// <summary>
            /// Enum UploadedEnum for uploaded
            /// </summary>
            [EnumMember(Value = "uploaded")]
            UploadedEnum = 0,
            /// <summary>
            /// Enum ProcessedEnum for processed
            /// </summary>
            [EnumMember(Value = "processed")]
            ProcessedEnum = 1,
            /// <summary>
            /// Enum ErrorEnum for error
            /// </summary>
            [EnumMember(Value = "error")]
            ErrorEnum = 2        }

        /// <summary>
        /// Deprecated. The current status of the file, which can be either &#x60;uploaded&#x60;, &#x60;processed&#x60;, or &#x60;error&#x60;.
        /// </summary>
        /// <value>Deprecated. The current status of the file, which can be either &#x60;uploaded&#x60;, &#x60;processed&#x60;, or &#x60;error&#x60;.</value>
        [Required]

        [DataMember(Name="status")]
        public StatusEnum? Status { get; set; }

        /// <summary>
        /// Deprecated. For details on why a fine-tuning training file failed validation, see the &#x60;error&#x60; field on &#x60;fine_tuning.job&#x60;.
        /// </summary>
        /// <value>Deprecated. For details on why a fine-tuning training file failed validation, see the &#x60;error&#x60; field on &#x60;fine_tuning.job&#x60;.</value>

        [DataMember(Name="status_details")]
        public string StatusDetails { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class OpenAIFile {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Bytes: ").Append(Bytes).Append("\n");
            sb.Append("  CreatedAt: ").Append(CreatedAt).Append("\n");
            sb.Append("  Filename: ").Append(Filename).Append("\n");
            sb.Append("  _Object: ").Append(_Object).Append("\n");
            sb.Append("  Purpose: ").Append(Purpose).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  StatusDetails: ").Append(StatusDetails).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj.GetType() == GetType() && Equals((OpenAIFile)obj);
        }

        /// <summary>
        /// Returns true if OpenAIFile instances are equal
        /// </summary>
        /// <param name="other">Instance of OpenAIFile to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(OpenAIFile other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Id == other.Id ||
                    Id != null &&
                    Id.Equals(other.Id)
                ) && 
                (
                    Bytes == other.Bytes ||
                    Bytes != null &&
                    Bytes.Equals(other.Bytes)
                ) && 
                (
                    CreatedAt == other.CreatedAt ||
                    CreatedAt != null &&
                    CreatedAt.Equals(other.CreatedAt)
                ) && 
                (
                    Filename == other.Filename ||
                    Filename != null &&
                    Filename.Equals(other.Filename)
                ) && 
                (
                    _Object == other._Object ||
                    _Object != null &&
                    _Object.Equals(other._Object)
                ) && 
                (
                    Purpose == other.Purpose ||
                    Purpose != null &&
                    Purpose.Equals(other.Purpose)
                ) && 
                (
                    Status == other.Status ||
                    Status != null &&
                    Status.Equals(other.Status)
                ) && 
                (
                    StatusDetails == other.StatusDetails ||
                    StatusDetails != null &&
                    StatusDetails.Equals(other.StatusDetails)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                var hashCode = 41;
                // Suitable nullity checks etc, of course :)
                    if (Id != null)
                    hashCode = hashCode * 59 + Id.GetHashCode();
                    if (Bytes != null)
                    hashCode = hashCode * 59 + Bytes.GetHashCode();
                    if (CreatedAt != null)
                    hashCode = hashCode * 59 + CreatedAt.GetHashCode();
                    if (Filename != null)
                    hashCode = hashCode * 59 + Filename.GetHashCode();
                    if (_Object != null)
                    hashCode = hashCode * 59 + _Object.GetHashCode();
                    if (Purpose != null)
                    hashCode = hashCode * 59 + Purpose.GetHashCode();
                    if (Status != null)
                    hashCode = hashCode * 59 + Status.GetHashCode();
                    if (StatusDetails != null)
                    hashCode = hashCode * 59 + StatusDetails.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(OpenAIFile left, OpenAIFile right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(OpenAIFile left, OpenAIFile right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}