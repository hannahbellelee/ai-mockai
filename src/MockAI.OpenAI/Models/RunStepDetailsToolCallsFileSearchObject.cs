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
    /// 
    /// </summary>
    [DataContract]
    public partial class RunStepDetailsToolCallsFileSearchObject : IEquatable<RunStepDetailsToolCallsFileSearchObject>, OneOfRunStepDetailsToolCallsObjectToolCallsItems 
    { 
        /// <summary>
        /// The ID of the tool call object.
        /// </summary>
        /// <value>The ID of the tool call object.</value>
        [Required]

        [DataMember(Name="id")]
        public string Id { get; set; }

        /// <summary>
        /// The type of tool call. This is always going to be `file_search` for this type of tool call.
        /// </summary>
        /// <value>The type of tool call. This is always going to be `file_search` for this type of tool call.</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum TypeEnum
        {
            /// <summary>
            /// Enum FileSearchEnum for file_search
            /// </summary>
            [EnumMember(Value = "file_search")]
            FileSearchEnum = 0        }

        /// <summary>
        /// The type of tool call. This is always going to be &#x60;file_search&#x60; for this type of tool call.
        /// </summary>
        /// <value>The type of tool call. This is always going to be &#x60;file_search&#x60; for this type of tool call.</value>
        [Required]

        [DataMember(Name="type")]
        public TypeEnum? Type { get; set; }

        /// <summary>
        /// For now, this is always going to be an empty object.
        /// </summary>
        /// <value>For now, this is always going to be an empty object.</value>
        [Required]

        [DataMember(Name="file_search")]
        public Object FileSearch { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class RunStepDetailsToolCallsFileSearchObject {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Type: ").Append(Type).Append("\n");
            sb.Append("  FileSearch: ").Append(FileSearch).Append("\n");
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
            return obj.GetType() == GetType() && Equals((RunStepDetailsToolCallsFileSearchObject)obj);
        }

        /// <summary>
        /// Returns true if RunStepDetailsToolCallsFileSearchObject instances are equal
        /// </summary>
        /// <param name="other">Instance of RunStepDetailsToolCallsFileSearchObject to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(RunStepDetailsToolCallsFileSearchObject other)
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
                    Type == other.Type ||
                    Type != null &&
                    Type.Equals(other.Type)
                ) && 
                (
                    FileSearch == other.FileSearch ||
                    FileSearch != null &&
                    FileSearch.Equals(other.FileSearch)
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
                    if (Type != null)
                    hashCode = hashCode * 59 + Type.GetHashCode();
                    if (FileSearch != null)
                    hashCode = hashCode * 59 + FileSearch.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(RunStepDetailsToolCallsFileSearchObject left, RunStepDetailsToolCallsFileSearchObject right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(RunStepDetailsToolCallsFileSearchObject left, RunStepDetailsToolCallsFileSearchObject right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
