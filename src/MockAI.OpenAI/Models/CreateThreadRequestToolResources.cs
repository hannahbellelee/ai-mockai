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
    /// A set of resources that are made available to the assistant&#x27;s tools in this thread. The resources are specific to the type of tool. For example, the &#x60;code_interpreter&#x60; tool requires a list of file IDs, while the &#x60;file_search&#x60; tool requires a list of vector store IDs. 
    /// </summary>
    [DataContract]
    public partial class CreateThreadRequestToolResources : IEquatable<CreateThreadRequestToolResources>
    { 
        /// <summary>
        /// Gets or Sets CodeInterpreter
        /// </summary>

        [DataMember(Name="code_interpreter")]
        public CreateAssistantRequestToolResourcesCodeInterpreter CodeInterpreter { get; set; }

        /// <summary>
        /// Gets or Sets FileSearch
        /// </summary>

        [DataMember(Name="file_search")]
        public CreateThreadRequestToolResourcesFileSearch FileSearch { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class CreateThreadRequestToolResources {\n");
            sb.Append("  CodeInterpreter: ").Append(CodeInterpreter).Append("\n");
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
            return obj.GetType() == GetType() && Equals((CreateThreadRequestToolResources)obj);
        }

        /// <summary>
        /// Returns true if CreateThreadRequestToolResources instances are equal
        /// </summary>
        /// <param name="other">Instance of CreateThreadRequestToolResources to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CreateThreadRequestToolResources other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    CodeInterpreter == other.CodeInterpreter ||
                    CodeInterpreter != null &&
                    CodeInterpreter.Equals(other.CodeInterpreter)
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
                    if (CodeInterpreter != null)
                    hashCode = hashCode * 59 + CodeInterpreter.GetHashCode();
                    if (FileSearch != null)
                    hashCode = hashCode * 59 + FileSearch.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(CreateThreadRequestToolResources left, CreateThreadRequestToolResources right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(CreateThreadRequestToolResources left, CreateThreadRequestToolResources right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
