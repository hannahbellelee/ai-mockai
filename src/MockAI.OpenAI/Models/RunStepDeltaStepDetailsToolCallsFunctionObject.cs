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
    public partial class RunStepDeltaStepDetailsToolCallsFunctionObject : IEquatable<RunStepDeltaStepDetailsToolCallsFunctionObject>, OneOfRunStepDeltaStepDetailsToolCallsObjectToolCallsItems 
    { 
        /// <summary>
        /// The index of the tool call in the tool calls array.
        /// </summary>
        /// <value>The index of the tool call in the tool calls array.</value>
        [Required]

        [DataMember(Name="index")]
        public int? Index { get; set; }

        /// <summary>
        /// The ID of the tool call object.
        /// </summary>
        /// <value>The ID of the tool call object.</value>

        [DataMember(Name="id")]
        public string Id { get; set; }

        /// <summary>
        /// The type of tool call. This is always going to be `function` for this type of tool call.
        /// </summary>
        /// <value>The type of tool call. This is always going to be `function` for this type of tool call.</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum TypeEnum
        {
            /// <summary>
            /// Enum FunctionEnum for function
            /// </summary>
            [EnumMember(Value = "function")]
            FunctionEnum = 0        }

        /// <summary>
        /// The type of tool call. This is always going to be &#x60;function&#x60; for this type of tool call.
        /// </summary>
        /// <value>The type of tool call. This is always going to be &#x60;function&#x60; for this type of tool call.</value>
        [Required]

        [DataMember(Name="type")]
        public TypeEnum? Type { get; set; }

        /// <summary>
        /// Gets or Sets Function
        /// </summary>

        [DataMember(Name="function")]
        public RunStepDeltaStepDetailsToolCallsFunctionObjectFunction Function { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class RunStepDeltaStepDetailsToolCallsFunctionObject {\n");
            sb.Append("  Index: ").Append(Index).Append("\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  Type: ").Append(Type).Append("\n");
            sb.Append("  Function: ").Append(Function).Append("\n");
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
            return obj.GetType() == GetType() && Equals((RunStepDeltaStepDetailsToolCallsFunctionObject)obj);
        }

        /// <summary>
        /// Returns true if RunStepDeltaStepDetailsToolCallsFunctionObject instances are equal
        /// </summary>
        /// <param name="other">Instance of RunStepDeltaStepDetailsToolCallsFunctionObject to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(RunStepDeltaStepDetailsToolCallsFunctionObject other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Index == other.Index ||
                    Index != null &&
                    Index.Equals(other.Index)
                ) && 
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
                    Function == other.Function ||
                    Function != null &&
                    Function.Equals(other.Function)
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
                    if (Index != null)
                    hashCode = hashCode * 59 + Index.GetHashCode();
                    if (Id != null)
                    hashCode = hashCode * 59 + Id.GetHashCode();
                    if (Type != null)
                    hashCode = hashCode * 59 + Type.GetHashCode();
                    if (Function != null)
                    hashCode = hashCode * 59 + Function.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(RunStepDeltaStepDetailsToolCallsFunctionObject left, RunStepDeltaStepDetailsToolCallsFunctionObject right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(RunStepDeltaStepDetailsToolCallsFunctionObject left, RunStepDeltaStepDetailsToolCallsFunctionObject right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
